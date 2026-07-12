//! Mark-and-sweep GC for Malm storage. Roots include retained, pinned, active,
//! recoverable, and disabled transactions plus per-state metadata. Unreadable
//! metadata is ignored for usage, aborts pruning, or causes over-retention with
//! `prune --force`.

use crate::app::validation::validate_name;
use crate::cas;
use crate::source::SourceKind;
use crate::source::git_url::{git_cache_root, git_sources_root, url_to_cache_name};
use crate::state::active_deployment::read_source_pointer;
use crate::state::ownership_store::read_ownership_for;
use crate::state::pins::all_pinned_ids;
use crate::state::record::{live_deployment_id_strict, restore_deployment_id};
use crate::state::state_namespaces;
use crate::state::tracking::TrackedRemote;
use crate::state::transaction::{RecordedOp, TransactionStore, transactions_dir};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Default, Clone, Copy)]
pub struct CategoryStat {
    pub bytes: u64,
    pub count: usize,
}

#[derive(Default, Clone, Copy)]
pub struct CategoryUsage {
    pub reachable: CategoryStat,
    pub reclaimable: CategoryStat,
}

#[derive(Default, Clone, Copy)]
pub struct Breakdown {
    pub transactions: CategoryUsage,
    pub blobs: CategoryUsage,
    pub sources: CategoryUsage,
    pub asset_archives: CategoryUsage,
    pub asset_payloads: CategoryUsage,
    pub git_sources: CategoryUsage,
    pub git_cache: CategoryUsage,
}

impl Breakdown {
    pub fn reclaimable_bytes(&self) -> u64 {
        [
            self.transactions,
            self.blobs,
            self.asset_archives,
            self.git_sources,
            self.git_cache,
        ]
        .iter()
        .map(|c| c.reclaimable.bytes)
        .sum()
    }

    pub fn pruned_transactions(&self) -> usize {
        self.transactions.reclaimable.count
    }
}

pub struct PruneReport {
    pub breakdown: Breakdown,
    pub dry_run: bool,
}

#[derive(Clone, Copy)]
pub struct PruneOptions {
    pub keep: usize,
    pub keep_per_state: Option<usize>,
    pub dry_run: bool,
    /// Keep everything referenced by a state's history when its metadata is
    /// unreadable, rather than aborting the prune.
    pub force: bool,
}

/// Controls how the mark pass handles unreadable state metadata. A destructive
/// prune must either fail closed or retain everything that might still be live.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MarkMode {
    /// Warn and continue because usage reporting deletes nothing.
    BestEffort,
    /// Abort pruning on unreadable metadata.
    Strict,
    /// Retain every object referenced by the affected state's transactions.
    ForceRetain,
}

pub fn usage(keep: usize, keep_per_state: Option<usize>) -> Result<Breakdown> {
    let marks = compute_marks(keep, keep_per_state, MarkMode::BestEffort)?;
    let (breakdown, _paths) = scan(&marks)?;
    Ok(breakdown)
}

pub fn prune(options: PruneOptions) -> Result<PruneReport> {
    let mode = if options.force {
        MarkMode::ForceRetain
    } else {
        MarkMode::Strict
    };
    let marks = compute_marks(options.keep, options.keep_per_state, mode)?;
    let (breakdown, reclaimable) = scan(&marks)?;

    if !options.dry_run {
        for path in reclaimable {
            remove_object(&path)?;
        }
    }

    Ok(PruneReport {
        breakdown,
        dry_run: options.dry_run,
    })
}

struct Marks {
    txns: HashSet<String>,
    sources: HashSet<String>,
    payloads: HashSet<String>,
    archives: HashSet<String>,
    blobs: HashSet<String>,
    git_sources: HashSet<(String, String)>,
    git_cache: HashSet<String>,
}

fn fail_closed(namespace: &str, what: &str, error: anyhow::Error) -> anyhow::Error {
    anyhow::anyhow!(
        "cannot prune: {what} for state '{namespace}' is unreadable ({error:#}); run \
         `malm state fsck` to inspect, or pass --force to prune anyway — everything \
         the affected state's history references will be retained"
    )
}

fn compute_marks(keep: usize, keep_per_state: Option<usize>, mode: MarkMode) -> Result<Marks> {
    let store = TransactionStore::new();
    let mut manifests = match mode {
        MarkMode::BestEffort => store.list_all()?,
        // An unreadable transaction cannot mark its objects, so pruning must
        // stop rather than delete data around it.
        MarkMode::Strict | MarkMode::ForceRetain => store.list_all_strict().context(
            "cannot prune with unreadable transaction records; run `malm state fsck` \
             (this is not bypassed by --force)",
        )?,
    };
    // IDs contain a zero-padded seconds/nanoseconds prefix, which breaks ties
    // in the second-granularity completion time.
    manifests.sort_by(|a, b| (b.completed_at, &b.id).cmp(&(a.completed_at, &a.id)));

    let mut txns: HashSet<String> = HashSet::new();

    match keep_per_state {
        Some(per) => {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for manifest in &manifests {
                let count = counts.entry(manifest.state_namespace()).or_default();
                if *count < per {
                    txns.insert(manifest.id.as_str().to_owned());
                    *count += 1;
                }
            }
        }
        None => {
            for manifest in manifests.iter().take(keep) {
                txns.insert(manifest.id.as_str().to_owned());
            }
        }
    }

    for manifest in manifests.iter().filter(|m| m.requires_recovery_retention()) {
        txns.insert(manifest.id.as_str().to_owned());
    }
    txns.extend(all_pinned_ids()?);

    let mut marks = Marks {
        txns,
        sources: HashSet::new(),
        payloads: HashSet::new(),
        archives: HashSet::new(),
        blobs: HashSet::new(),
        git_sources: HashSet::new(),
        git_cache: HashSet::new(),
    };

    // Under --force, these namespaces retain their full transaction history.
    let mut broken_namespaces: HashSet<String> = HashSet::new();

    let sources_dir = cas::sources_dir();
    let payloads_dir = cas::asset_payloads_dir();
    for namespace in state_namespaces()? {
        if validate_name(&namespace, "state name").is_err() {
            match mode {
                MarkMode::BestEffort => {
                    crate::warn_term!(
                        "warning: state directory {namespace:?} has an invalid name; its \
                         metadata is ignored during GC mark"
                    );
                    continue;
                }
                MarkMode::Strict => anyhow::bail!(
                    "cannot prune: state directory {namespace:?} has an invalid name; run \
                     `malm state fsck` to inspect, or pass --force to prune anyway"
                ),
                MarkMode::ForceRetain => {
                    crate::warn_term!(
                        "warning: state directory {namespace:?} has an invalid name; \
                         retaining everything its history references"
                    );
                    broken_namespaces.insert(namespace);
                    continue;
                }
            }
        }

        match live_deployment_id_strict(&namespace) {
            Ok(Some(id)) => {
                marks.txns.insert(id);
            }
            Ok(None) => {}
            Err(error) => match mode {
                MarkMode::BestEffort => crate::warn_term!(
                    "warning: could not resolve active transaction for state {namespace:?}: \
                     {error:#}"
                ),
                MarkMode::Strict => {
                    return Err(fail_closed(
                        &namespace,
                        "the active deployment record",
                        error,
                    ));
                }
                MarkMode::ForceRetain => {
                    broken_namespaces.insert(namespace.clone());
                }
            },
        }

        match read_ownership_for(&namespace) {
            Ok(ownership) => {
                for entry in ownership.iter() {
                    if let Some(id) =
                        leaf_under(&entry.source, &sources_dir).and_then(valid_object_mark)
                    {
                        marks.sources.insert(id);
                    }
                    if let Some(id) =
                        leaf_under(&entry.source, &payloads_dir).and_then(valid_object_mark)
                    {
                        marks.payloads.insert(id);
                    }
                }
            }
            Err(error) => match mode {
                MarkMode::BestEffort => crate::warn_term!(
                    "warning: could not read ownership for state {namespace:?} during GC \
                     mark: {error:#}"
                ),
                MarkMode::Strict => {
                    return Err(fail_closed(&namespace, "the ownership index", error));
                }
                MarkMode::ForceRetain => {
                    broken_namespaces.insert(namespace.clone());
                }
            },
        }

        match read_source_pointer(&namespace) {
            Ok(Some(pointer)) => {
                if let Some(id) = leaf_under(&pointer, &sources_dir).and_then(valid_object_mark) {
                    marks.sources.insert(id);
                }
            }
            Ok(None) => {}
            Err(error) => match mode {
                MarkMode::BestEffort => crate::warn_term!(
                    "warning: could not read source pointer for state {namespace:?}: {error:#}"
                ),
                MarkMode::Strict => {
                    return Err(fail_closed(&namespace, "the source pointer", error));
                }
                MarkMode::ForceRetain => {
                    broken_namespaces.insert(namespace.clone());
                }
            },
        }

        match TrackedRemote::load_for_state(&namespace) {
            Ok(Some(tracking)) => {
                let cache_name = url_to_cache_name(&tracking.url);
                marks.git_cache.insert(cache_name.clone());
                marks
                    .git_sources
                    .insert((cache_name, tracking.applied_commit.clone()));
            }
            Ok(None) => {}
            Err(error) => match mode {
                MarkMode::BestEffort => {
                    crate::warn_term!(
                        "warning: could not read tracking for state {namespace:?}: {error:#}"
                    );
                }
                MarkMode::Strict => {
                    return Err(fail_closed(&namespace, "the tracking record", error));
                }
                MarkMode::ForceRetain => {
                    broken_namespaces.insert(namespace.clone());
                }
            },
        }

        // Keep a disabled state's restore target so `state enable` can use it.
        match restore_deployment_id(&namespace) {
            Ok(Some(restore)) => {
                marks.txns.insert(restore);
            }
            Ok(None) => {}
            Err(error) => match mode {
                MarkMode::BestEffort => crate::warn_term!(
                    "warning: could not read the state record for state {namespace:?}: \
                     {error:#}"
                ),
                MarkMode::Strict => {
                    return Err(fail_closed(&namespace, "the state record", error));
                }
                MarkMode::ForceRetain => {
                    broken_namespaces.insert(namespace.clone());
                }
            },
        }
    }

    // If metadata was unreadable under --force, keep every transaction in that
    // namespace and every object those transactions reference.
    if !broken_namespaces.is_empty() {
        for manifest in &manifests {
            if broken_namespaces.contains(manifest.state_namespace()) {
                marks.txns.insert(manifest.id.as_str().to_owned());
            }
        }
    }

    for manifest in &manifests {
        if !marks.txns.contains(manifest.id.as_str()) {
            continue;
        }
        marks
            .sources
            .insert(manifest.source_snapshot_id.as_str().to_owned());

        if let Some(SourceKind::Git { url, commit }) =
            manifest.source.as_ref().map(|identity| &identity.kind)
        {
            let cache_name = url_to_cache_name(url);
            marks
                .git_sources
                .insert((cache_name.clone(), commit.clone()));
            marks.git_cache.insert(cache_name);
        }
        for op in &manifest.operations {
            // Rollback of a crashed disable reinstalls removed assets from
            // their payloads.
            if let RecordedOp::RemoveAsset { payload, .. } = op
                && let Some(id) = leaf_under(payload, &payloads_dir).and_then(valid_object_mark)
            {
                marks.payloads.insert(id);
            }
            if let RecordedOp::InstallAsset {
                payload,
                archive_sha256,
                ..
            } = op
            {
                if let Some(id) = leaf_under(payload, &payloads_dir).and_then(valid_object_mark) {
                    marks.payloads.insert(id);
                }
                if let Some(sha) = archive_sha256
                    && let Some(id) =
                        valid_object_mark(format!("sha256-{}", sha.to_ascii_lowercase()))
                {
                    marks.archives.insert(id);
                }
            }
        }
        for asset in &manifest.desired_assets {
            if let Some(id) = leaf_under(&asset.source, &payloads_dir).and_then(valid_object_mark) {
                marks.payloads.insert(id);
            }
        }
    }

    for id in &marks.sources {
        if let Ok(dir) = cas::sources_object_dir(id) {
            mark_tree_blobs(&dir, id, &mut marks.blobs)?;
        }
    }
    for id in &marks.payloads {
        if let Ok(dir) = cas::asset_payload_object(id) {
            mark_tree_blobs(&dir, id, &mut marks.blobs)?;
        }
    }

    Ok(marks)
}

fn scan(marks: &Marks) -> Result<(Breakdown, Vec<PathBuf>)> {
    let mut breakdown = Breakdown::default();
    let mut reclaimable = Vec::new();

    let (usage, mut paths) = scan_dir(&transactions_dir(), &marks.txns, EntryKind::Dir)?;
    breakdown.transactions = usage;
    reclaimable.append(&mut paths);

    let (usage, mut paths) = scan_dir(&cas::blobs_dir(), &marks.blobs, EntryKind::File)?;
    breakdown.blobs = usage;
    reclaimable.append(&mut paths);

    let (usage, mut paths) = scan_dir(&cas::sources_dir(), &marks.sources, EntryKind::Dir)?;
    breakdown.sources = usage;
    reclaimable.append(&mut paths);

    let (usage, mut paths) =
        scan_dir(&cas::asset_archives_dir(), &marks.archives, EntryKind::File)?;
    breakdown.asset_archives = usage;
    reclaimable.append(&mut paths);

    let (usage, mut paths) = scan_dir(&cas::asset_payloads_dir(), &marks.payloads, EntryKind::Dir)?;
    breakdown.asset_payloads = usage;
    reclaimable.append(&mut paths);

    let (usage, mut paths) = scan_dir(&git_cache_root(), &marks.git_cache, EntryKind::Dir)?;
    breakdown.git_cache = usage;
    reclaimable.append(&mut paths);

    let (usage, mut paths) = scan_git_sources(&marks.git_sources)?;
    breakdown.git_sources = usage;
    reclaimable.append(&mut paths);

    reclaimable.append(&mut reclaimable_asset_index(&marks.archives)?);
    reclaimable.append(&mut reclaimable_tree_blob_index(marks)?);

    Ok((breakdown, reclaimable))
}

fn reclaimable_tree_blob_index(marks: &Marks) -> Result<Vec<PathBuf>> {
    let dir = cas::tree_blob_index_dir();
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", dir.display())),
    };
    let mut reclaimable = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with('.') {
            continue;
        }
        let id = name.strip_suffix(".json").unwrap_or(name);
        if !marks.sources.contains(id) && !marks.payloads.contains(id) {
            reclaimable.push(entry.path());
        }
    }
    Ok(reclaimable)
}

fn reclaimable_asset_index(marked_archives: &HashSet<String>) -> Result<Vec<PathBuf>> {
    let dir = cas::asset_index_dir();
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", dir.display())),
    };
    let mut reclaimable = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with('.') {
            continue;
        }
        let archive_id = name.strip_suffix(".json").unwrap_or(name);
        if !marked_archives.contains(archive_id) {
            reclaimable.push(entry.path());
        }
    }
    Ok(reclaimable)
}

// Reclaim a URL cache only when none of its commits are live. Digest marker
// names identify the corresponding commit directories.
fn scan_git_sources(marked: &HashSet<(String, String)>) -> Result<(CategoryUsage, Vec<PathBuf>)> {
    let mut usage = CategoryUsage::default();
    let mut reclaimable = Vec::new();
    let root = git_sources_root();
    let url_dirs = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((usage, reclaimable)),
        Err(e) => return Err(e).with_context(|| format!("read {}", root.display())),
    };
    for url_dir in url_dirs {
        let url_dir = url_dir.with_context(|| format!("read entry in {}", root.display()))?;
        let cache_name = url_dir.file_name();
        let Some(cache_name) = cache_name.to_str() else {
            continue;
        };
        if cache_name.starts_with('.') || !url_dir.file_type()?.is_dir() {
            continue;
        }
        let url_path = url_dir.path();
        let mut live_commits = 0usize;
        let commit_entries =
            fs::read_dir(&url_path).with_context(|| format!("read {}", url_path.display()))?;
        for commit in commit_entries {
            let commit = commit.with_context(|| format!("read entry in {}", url_path.display()))?;
            let commit_name = commit.file_name();
            let Some(commit_name) = commit_name.to_str() else {
                continue;
            };
            if let Some(commit_sha) = commit_name
                .strip_prefix('.')
                .and_then(|name| name.strip_suffix(".malm-tree-sha256"))
            {
                if !marked.contains(&(cache_name.to_owned(), commit_sha.to_owned())) {
                    reclaimable.push(commit.path());
                }
                continue;
            }
            if commit_name.starts_with('.') {
                continue;
            }
            let commit_path = commit.path();
            let size = get_dir_size(&commit_path)?;
            if marked.contains(&(cache_name.to_owned(), commit_name.to_owned())) {
                usage.reachable.bytes += size;
                usage.reachable.count += 1;
                live_commits += 1;
            } else {
                usage.reclaimable.bytes += size;
                usage.reclaimable.count += 1;
                reclaimable.push(commit_path);
            }
        }
        if live_commits == 0 {
            reclaimable.push(url_path);
        }
    }
    Ok((usage, reclaimable))
}

#[derive(Clone, Copy, PartialEq)]
enum EntryKind {
    Dir,
    File,
}

fn scan_dir(
    dir: &Path,
    marked: &HashSet<String>,
    kind: EntryKind,
) -> Result<(CategoryUsage, Vec<PathBuf>)> {
    let mut usage = CategoryUsage::default();
    let mut reclaimable = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((usage, reclaimable)),
        Err(e) => return Err(e).with_context(|| format!("read {}", dir.display())),
    };
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let size = match kind {
            EntryKind::File => entry.metadata()?.len(),
            EntryKind::Dir => get_dir_size(&path)?,
        };
        if marked.contains(name) {
            usage.reachable.bytes += size;
            usage.reachable.count += 1;
        } else {
            usage.reclaimable.bytes += size;
            usage.reclaimable.count += 1;
            reclaimable.push(path);
        }
    }
    Ok((usage, reclaimable))
}

fn remove_object(path: &Path) -> Result<()> {
    cas::remove_unreachable_object(path)
}

// Use the recorded index when possible. Otherwise hash the tree and save the
// result for later scans.
fn mark_tree_blobs(dir: &Path, id: &str, blobs: &mut HashSet<String>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    if let Some(recorded) = cas::recorded_tree_blobs(id)? {
        blobs.extend(recorded);
        return Ok(());
    }
    let mut found = Vec::new();
    for entry in walkdir::WalkDir::new(dir) {
        let entry = entry.with_context(|| format!("walk {}", dir.display()))?;
        if entry.file_type().is_file() {
            found.push(cas::hash_file(entry.path())?);
        }
    }
    found.sort();
    found.dedup();
    let _ = cas::record_tree_blobs(id, &found);
    blobs.extend(found);
    Ok(())
}

fn leaf_under(path: &Path, base: &Path) -> Option<String> {
    path.strip_prefix(base)
        .ok()
        .and_then(|rel| rel.components().next())
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
}

fn valid_object_mark(id: String) -> Option<String> {
    cas::validate_object_id(&id).ok().map(|()| id)
}

fn get_dir_size(path: &Path) -> Result<u64> {
    let mut size = 0;
    if path.is_dir() {
        for entry in walkdir::WalkDir::new(path) {
            let entry = entry?;
            if entry.file_type().is_file() {
                size += entry.metadata()?.len();
            }
        }
    }
    Ok(size)
}
