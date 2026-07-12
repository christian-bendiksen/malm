//! URL helpers: deterministic cache-directory naming, credential redaction,
//! and https/userinfo validation.

use crate::paths::xdg_state_home;
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub(crate) fn git_cache_root() -> PathBuf {
    xdg_state_home().join("malm/cache/git")
}

pub(crate) fn git_sources_root() -> PathBuf {
    xdg_state_home().join("malm/sources/git")
}

pub fn cache_dir_for_url(url: &str) -> PathBuf {
    git_cache_root().join(url_to_cache_name(url))
}

pub fn source_dir_for_url_commit(url: &str, commit: &str) -> PathBuf {
    git_sources_root().join(url_to_cache_name(url)).join(commit)
}

// Userinfo is stripped before hashing: user@host and host share a cache.
pub(crate) fn url_to_cache_name(url: &str) -> String {
    let safe_url = strip_url_userinfo(url);

    let hash = Sha256::digest(safe_url.as_bytes());
    let hash_str = hex::encode(&hash[..8]);

    let prefix: String = safe_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("git@")
        .chars()
        .take(40)
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();

    format!("{prefix}_{hash_str}")
}

// Split within the authority only, so an @ in the path is not userinfo.
fn split_url_userinfo(url: &str) -> Option<(&str, &str, &str, &str)> {
    let (scheme, after_scheme) = url.split_once("://")?;
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let (authority, rest) = after_scheme.split_at(authority_end);
    let (userinfo, host) = authority.rsplit_once('@')?;
    Some((scheme, userinfo, host, rest))
}

pub fn redact_url(url: &str) -> String {
    match split_url_userinfo(url) {
        Some((scheme, _, host, rest)) => format!("{scheme}://<redacted>@{host}{rest}"),
        None => url.to_owned(),
    }
}

fn strip_url_userinfo(url: &str) -> String {
    match split_url_userinfo(url) {
        Some((scheme, _, host, rest)) => format!("{scheme}://{host}{rest}"),
        None => url.to_owned(),
    }
}

pub fn is_remote_url(s: &str) -> bool {
    s.starts_with("https://") || s.starts_with("http://")
}

pub fn require_https(url: &str) -> Result<()> {
    if !url.starts_with("https://") {
        let shown = redact_url(url);

        if url.starts_with("http://") {
            anyhow::bail!(
                "only HTTPS URLs are accepted for remote repositories (got: {shown})\n\
                 Use a URL starting with https://"
            );
        }
        anyhow::bail!(
            "only HTTPS URLs are accepted for remote repositories (got: {shown})\n\
        Use a URL starting with https://"
        );
    }
    reject_url_userinfo(url)?;
    Ok(())
}

pub fn reject_url_userinfo(url: &str) -> Result<()> {
    if split_url_userinfo(url).is_some() {
        anyhow::bail!(
            "URLs with embedded credentials are not supported (got: {}).\n\
             Use a Git credential helper instead.",
            redact_url(url)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_name_is_deterministic_and_url_specific() {
        let url = "https://example.com/dotfiles.git";
        assert_eq!(url_to_cache_name(url), url_to_cache_name(url));
        assert_ne!(
            url_to_cache_name(url),
            url_to_cache_name("https://example.com/other.git")
        );
    }

    #[test]
    fn cache_name_ignores_embedded_userinfo() {
        assert_eq!(
            url_to_cache_name("https://user@example.com/dotfiles.git"),
            url_to_cache_name("https://example.com/dotfiles.git")
        );
    }

    #[test]
    fn at_sign_in_path_is_not_userinfo() {
        assert_eq!(
            redact_url("https://example.com/repo@v2"),
            "https://example.com/repo@v2"
        );
        assert_ne!(
            url_to_cache_name("https://example.com/repo@v2"),
            url_to_cache_name("https://other.com/thing@v2")
        );
        assert!(reject_url_userinfo("https://example.com/repo@v2").is_ok());
        assert!(reject_url_userinfo("https://user:pw@example.com/repo").is_err());
    }

    #[test]
    fn redact_hides_userinfo_but_keeps_path() {
        assert_eq!(
            redact_url("https://user:secret@example.com/repo.git?x=1"),
            "https://<redacted>@example.com/repo.git?x=1"
        );
    }
}
