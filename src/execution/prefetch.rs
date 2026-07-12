//! Downloads, verifies, and extracts assets into the CAS before target changes.

use crate::execution::asset::build_asset_payload_object;
use crate::planning::plan::{DeploymentPlan, Operation};
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Maximum simultaneous asset downloads. Each fetch can buffer up to
/// `DownloadLimits::max_bytes` of temp data, so unbounded parallelism on a
/// many-core host could reserve large amounts of memory and open a large
/// number of connections for a plan with many assets.
const MAX_CONCURRENT_DOWNLOADS: usize = 8;

/// Asset payloads staged into the CAS ahead of execution, keyed by the index
/// of their `InstallAsset` operation in the plan.
pub(super) struct PrefetchedAssets {
    payloads: HashMap<usize, PathBuf>,
    /// Present for payloads whose top level is all directories: those install
    /// per entry (`dst/<entry>`) so assets can share an extraction root.
    merge_entries: HashMap<usize, Vec<String>>,
}

impl PrefetchedAssets {
    pub fn payload_for(&self, op_index: usize, name: &str) -> Result<&Path> {
        self.payloads
            .get(&op_index)
            .map(PathBuf::as_path)
            .ok_or_else(|| anyhow::anyhow!("asset '{name}' was not prefetched (internal error)"))
    }

    pub fn merge_entries_for(&self, op_index: usize) -> Option<&[String]> {
        self.merge_entries.get(&op_index).map(Vec::as_slice)
    }
}

/// Download, verify, and extract every asset in the plan into the CAS before
/// any target-filesystem mutation. Fetches run in parallel but capped at
/// [`MAX_CONCURRENT_DOWNLOADS`]; if any of them fails the apply stops here,
/// with the target filesystem untouched.
pub(super) fn prefetch_assets(plan: &DeploymentPlan, allow_ssrf: bool) -> Result<PrefetchedAssets> {
    let downloads: Vec<(usize, &str, &str, &Option<String>, _)> = plan
        .operations()
        .iter()
        .enumerate()
        .filter_map(|(index, op)| match op {
            Operation::InstallAsset {
                name,
                url,
                sha256,
                format,
                ..
            } => Some((index, name.as_str(), url.as_str(), sha256, *format)),
            _ => None,
        })
        .collect();

    if downloads.is_empty() {
        let prefetched = PrefetchedAssets {
            payloads: HashMap::new(),
            merge_entries: HashMap::new(),
        };
        validate_placements(plan, &prefetched)?;
        return Ok(prefetched);
    }

    // Use a bounded pool to limit simultaneous connections and buffered
    // archives. The work is I/O-bound, so a small pool is enough.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(MAX_CONCURRENT_DOWNLOADS.min(downloads.len()))
        .build()
        .context("build asset prefetch thread pool")?;
    let payloads = pool.install(|| {
        downloads
            .par_iter()
            .map(|&(index, name, url, sha256, format)| {
                let payload = build_asset_payload_object(name, url, sha256, format, allow_ssrf)
                    .with_context(|| format!("prefetch asset '{name}'"))?;
                Ok((index, payload))
            })
            .collect::<Result<HashMap<usize, PathBuf>>>()
    })?;

    let mut merge_entries = HashMap::new();
    for (&index, payload) in &payloads {
        if let Some(entries) = crate::cas::payload_merge_entries(payload)? {
            merge_entries.insert(index, entries);
        }
    }

    let prefetched = PrefetchedAssets {
        payloads,
        merge_entries,
    };
    validate_placements(plan, &prefetched)?;
    Ok(prefetched)
}

/// The plan-time graph check lets asset destinations share and nest because
/// each install manages only its payload's top-level entries. Now that every
/// payload is in the CAS the concrete entry paths are known, so collisions
/// between assets are refused here, before any target mutation.
fn validate_placements(plan: &DeploymentPlan, prefetched: &PrefetchedAssets) -> Result<()> {
    let mut placements: Vec<(PathBuf, &str)> = Vec::new();
    for (index, op) in plan.operations().iter().enumerate() {
        match op {
            Operation::InstallAsset { name, target, .. } => {
                match prefetched.merge_entries_for(index) {
                    Some(entries) => {
                        placements.extend(entries.iter().map(|e| (target.join(e), name.as_str())));
                    }
                    None => placements.push((target.clone(), name.as_str())),
                }
            }
            Operation::RestoreAsset { name, target, .. } => {
                placements.push((target.clone(), name.as_str()));
            }
            _ => {}
        }
    }

    for (i, (left_path, left_name)) in placements.iter().enumerate() {
        for (right_path, right_name) in placements.iter().skip(i + 1) {
            let collides = left_path == right_path
                || left_path.starts_with(right_path)
                || right_path.starts_with(left_path);
            if collides {
                let deeper = if right_path.starts_with(left_path) {
                    right_path
                } else {
                    left_path
                };
                anyhow::bail!(
                    "asset \"{left_name}\" and asset \"{right_name}\" would both manage {}: \
                     adjust their destinations so the extracted entries stay disjoint",
                    deeper.display()
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::ArchiveFormat;

    fn install(name: &str, dst: &str) -> Operation {
        Operation::InstallAsset {
            name: name.to_owned(),
            url: "https://example.invalid/a.tar.xz".to_owned(),
            target: PathBuf::from(dst),
            sha256: None,
            format: ArchiveFormat::TarXz,
            refresh_font_cache: false,
        }
    }

    fn plan_with(ops: Vec<Operation>) -> DeploymentPlan {
        let mut plan = DeploymentPlan::new();
        for op in ops {
            plan.push(op);
        }
        plan
    }

    fn prefetched(merge: &[(usize, &[&str])]) -> PrefetchedAssets {
        PrefetchedAssets {
            payloads: HashMap::new(),
            merge_entries: merge
                .iter()
                .map(|(index, names)| (*index, names.iter().map(|s| (*s).to_owned()).collect()))
                .collect(),
        }
    }

    #[test]
    fn disjoint_merge_entries_share_a_destination() {
        let plan = plan_with(vec![install("a", "/themes"), install("b", "/themes")]);
        let pre = prefetched(&[(0, &["adw-gtk3", "adw-gtk3-dark"]), (1, &["eldritch"])]);
        assert!(validate_placements(&plan, &pre).is_ok());
    }

    #[test]
    fn colliding_and_whole_tree_placements_are_refused() {
        let plan = plan_with(vec![install("a", "/themes"), install("b", "/themes")]);

        let pre = prefetched(&[(0, &["shared"]), (1, &["shared"])]);
        let error = validate_placements(&plan, &pre).unwrap_err().to_string();
        assert!(
            error.contains("would both manage /themes/shared"),
            "{error}"
        );

        // A flat archive (no merge entries) manages its whole destination and
        // may not share it with another asset's entries.
        let pre = prefetched(&[(0, &["adw-gtk3"])]);
        let error = validate_placements(&plan, &pre).unwrap_err().to_string();
        assert!(error.contains("would both manage"), "{error}");
    }
}
