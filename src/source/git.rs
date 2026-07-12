//! Git source resolution: bare mirror cache, ref-to-commit resolution, and
//! commit materialization into the source store.

use crate::fs::lock::lock_exclusive_with_feedback;
use crate::source::git_process::{git_capture, git_run};
use crate::source::{ResolvedSource, SourceIdentity};
use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::app::validation::validate_commit_sha;
pub use crate::source::git_archive::materialize_commit;
pub use crate::source::git_process::check_git_available;
pub use crate::source::git_url::{
    cache_dir_for_url, is_remote_url, redact_url, reject_url_userinfo, require_https,
};
use crate::source::local::resolve;

pub fn validate_branch_name(branch: &str) -> Result<()> {
    validate_ref_name("branch", &format!("refs/heads/{branch}"))
}

pub fn validate_tag_name(tag: &str) -> Result<()> {
    validate_ref_name("tag", &format!("refs/tags/{tag}"))
}

fn validate_ref_name(label: &str, full_ref: &str) -> Result<()> {
    check_git_available()?;
    git_capture(&[OsStr::new("check-ref-format"), OsStr::new(full_ref)])
        .map(|_| ())
        .map_err(|_| anyhow::anyhow!("invalid Git {label} name: {full_ref:?}"))
}

pub enum SourceSpec {
    Local {
        path: PathBuf,
    },
    Git {
        url: String,
        reference: GitReference,
    },
}

pub enum GitReference {
    Branch(String),
    Tag(String),
    Commit(String),
    DefaultBranch,
}

impl SourceSpec {
    pub fn local(path: PathBuf) -> Self {
        Self::Local { path }
    }

    pub fn resolve(&self) -> Result<ResolvedSource> {
        match self {
            Self::Local { path } => resolve(path),
            Self::Git { url, reference, .. } => resolve_git(url, reference),
        }
    }
}

fn resolve_git(url: &str, reference: &GitReference) -> Result<ResolvedSource> {
    check_git_available()?;

    let cache = cache_dir_for_url(url);

    let commit = match reference {
        // Commits are immutable: try the cache before fetching. Branches and
        // tags always fetch because they move.
        GitReference::Commit(commit) => {
            let cached = if cache.exists() {
                resolve_commit(&cache, commit).ok()
            } else {
                None
            };
            match cached {
                Some(sha) => sha,
                None => {
                    ensure_fetched(url)?;
                    resolve_commit(&cache, commit)?
                }
            }
        }
        GitReference::Branch(branch) => {
            ensure_fetched(url)?;
            resolve_branch_to_commit(&cache, branch)?
        }
        GitReference::Tag(tag) => {
            ensure_fetched(url)?;
            resolve_tag_to_commit(&cache, tag)?
        }
        GitReference::DefaultBranch => {
            ensure_fetched(url)?;
            let branch = default_branch_name(&cache)?;
            resolve_branch_to_commit(&cache, &branch)?
        }
    };

    let source_root = materialize_commit(url, &cache, &commit)
        .with_context(|| format!("materialize {commit}"))?;

    let identity = SourceIdentity::git(url.to_owned(), commit);

    Ok(ResolvedSource::remote(source_root, identity))
}

pub fn ensure_fetched(url: &str) -> Result<()> {
    let cache = cache_dir_for_url(url);
    let shown = redact_url(url);
    let parent = cache.parent().expect("cache dir always has a parent");
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let lock_path = parent.join(format!(
        ".{}.malm-fetch.lock",
        cache.file_name().and_then(|n| n.to_str()).unwrap_or("repo")
    ));
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open fetch lock {}", lock_path.display()))?;
    lock_exclusive_with_feedback(&lock, "source fetch lock")?;

    if !cache.exists() {
        git_run(&[
            OsStr::new("clone"),
            OsStr::new("--bare"),
            OsStr::new(url),
            cache.as_os_str(),
        ])
        .with_context(|| format!("clone {shown}"))?;
    }

    git_run(&[
        OsStr::new("-C"),
        cache.as_os_str(),
        OsStr::new("fetch"),
        OsStr::new("--prune"),
        OsStr::new("--tags"),
        OsStr::new("origin"),
        OsStr::new("+refs/heads/*:refs/remotes/origin/*"),
    ])
    .with_context(|| format!("fetch {shown}"))?;

    Ok(())
}

// ^{} peels annotated tags to the commit; fall back to the raw ref for
// plain commits.
pub fn resolve_commit(cache: &Path, git_ref: &str) -> Result<String> {
    validate_commit_sha(git_ref)?;
    let deref = format!("{git_ref}^{{}}");
    match rev_parse_verify(cache, &deref) {
        Ok(sha) => Ok(sha),
        Err(_) => rev_parse_verify(cache, git_ref)
            .with_context(|| format!("cannot resolve '{git_ref}' in the cached repository")),
    }
}

pub fn resolve_branch_to_commit(cache: &Path, branch: &str) -> Result<String> {
    let refname = format!("refs/remotes/origin/{branch}^{{commit}}");
    // Replace raw `rev-parse` output, which exposes cache paths and argv, with
    // a useful list of available branches.
    rev_parse_verify(cache, &refname)
        .map_err(|_| ref_not_found_error("branch", branch, &list_cached_refs(cache, Ref::Branch)))
}

pub fn resolve_tag_to_commit(cache: &Path, tag: &str) -> Result<String> {
    let refname = format!("refs/tags/{tag}^{{}}");
    rev_parse_verify(cache, &refname)
        .map_err(|_| ref_not_found_error("tag", tag, &list_cached_refs(cache, Ref::Tag)))
}

#[derive(Clone, Copy)]
enum Ref {
    Branch,
    Tag,
}

/// List the branch or tag names known to the bare cache. Best-effort: on any
/// git error this returns empty so the caller still reports "not found".
fn list_cached_refs(cache: &Path, kind: Ref) -> Vec<String> {
    let pattern = match kind {
        Ref::Branch => "refs/remotes/origin/",
        Ref::Tag => "refs/tags/",
    };
    let out = git_capture(&[
        OsStr::new("-C"),
        cache.as_os_str(),
        OsStr::new("for-each-ref"),
        OsStr::new("--format=%(refname:short)"),
        OsStr::new(pattern),
    ])
    .unwrap_or_default();

    out.lines()
        .map(|line| line.trim().trim_start_matches("origin/").to_owned())
        // `origin/HEAD` is a symbolic pointer, not a branch a user can name.
        .filter(|name| !name.is_empty() && name != "HEAD")
        .collect()
}

/// Report available names and a close match without exposing the Git invocation.
fn ref_not_found_error(kind: &str, name: &str, available: &[String]) -> anyhow::Error {
    if available.is_empty() {
        return anyhow::anyhow!("{kind} '{name}' not found in the remote repository");
    }
    let list = available.join(", ");
    let suggestion = closest_match(name, available)
        .map(|hit| format!("\n  (did you mean '{hit}'?)"))
        .unwrap_or_default();
    anyhow::anyhow!(
        "{kind} '{name}' not found in the remote repository\n  \
         available {kind}es: {list}{suggestion}"
    )
}

/// Return the nearest name when it is close enough to suggest.
fn closest_match<'a>(typed: &str, candidates: &'a [String]) -> Option<&'a str> {
    let threshold = (typed.len() / 2).max(2);
    candidates
        .iter()
        .map(|candidate| (levenshtein(typed, candidate), candidate))
        .filter(|(distance, _)| *distance <= threshold)
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, candidate)| candidate.as_str())
}

fn levenshtein(a: &str, b: &str) -> usize {
    let b_chars: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    let mut curr = vec![0; b_chars.len() + 1];
    for (i, a_ch) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, b_ch) in b_chars.iter().enumerate() {
            let cost = usize::from(a_ch != *b_ch);
            curr[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b_chars.len()]
}

fn rev_parse_verify(cache: &Path, git_ref: &str) -> Result<String> {
    git_capture(&[
        OsStr::new("-C"),
        cache.as_os_str(),
        OsStr::new("rev-parse"),
        OsStr::new("--verify"),
        OsStr::new("--end-of-options"),
        OsStr::new(git_ref),
    ])
}

pub fn default_branch_name(cache: &Path) -> Result<String> {
    git_capture(&[
        OsStr::new("-C"),
        cache.as_os_str(),
        OsStr::new("symbolic-ref"),
        OsStr::new("--short"),
        OsStr::new("HEAD"),
    ])
    .context("cannot determine default branch name")
}

pub fn log_oneline_range(cache: &Path, old: &str, new: &str) -> Result<Vec<String>> {
    let range = format!("{old}..{new}");
    let raw = git_capture(&[
        OsStr::new("-C"),
        cache.as_os_str(),
        OsStr::new("log"),
        OsStr::new("--oneline"),
        OsStr::new(&range),
    ])?;
    Ok(raw
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_owned())
        .collect())
}
