//! Parses, resolves, and formats CLI-only typed short IDs.

use anyhow::{Result, bail, ensure};
use malm_types::{Digest, PreparedId};

const MIN_SELECTOR_HEX: usize = 8;
const DEFAULT_DISPLAY_HEX: usize = 12;
const SHA256_HEX: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum IdDomain {
    Plan,
    Generation,
    Blob,
    Pack,
    File,
    Symlink,
    Tree,
    Graph,
}

impl IdDomain {
    pub(super) const fn tag(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Generation => "gen",
            Self::Blob => "blob",
            Self::Pack => "pack",
            Self::File => "file",
            Self::Symlink => "symlink",
            Self::Tree => "tree",
            Self::Graph => "graph",
        }
    }
}

enum Selector<T> {
    Exact(T),
    Prefix(String),
}

pub(super) fn resolve_plan(reference: &str, candidates: &[PreparedId]) -> Result<PreparedId> {
    match parse_plan(reference)? {
        Selector::Exact(plan) => Ok(plan),
        Selector::Prefix(prefix) => {
            resolve_unique(IdDomain::Plan, reference, &prefix, candidates, prepared_hex)
        }
    }
}

pub(super) fn resolve_digest(
    reference: &str,
    domain: IdDomain,
    candidates: &[Digest],
) -> Result<Digest> {
    ensure!(domain != IdDomain::Plan, "plan IDs use the plan selector");
    match parse_digest(reference, domain)? {
        Selector::Exact(digest) => Ok(digest),
        Selector::Prefix(prefix) => {
            resolve_unique(domain, reference, &prefix, candidates, digest_hex)
        }
    }
}

pub(super) fn display_plan(plan: &PreparedId, verbose: bool) -> String {
    display_plan_unique(plan, &[], verbose)
}

pub(super) fn display_plan_unique(
    plan: &PreparedId,
    candidates: &[PreparedId],
    verbose: bool,
) -> String {
    display(
        IdDomain::Plan,
        plan.as_str(),
        prepared_hex(plan),
        candidates.iter().map(prepared_hex),
        verbose,
    )
}

pub(super) fn display_digest(domain: IdDomain, digest: &Digest, verbose: bool) -> String {
    display_digest_unique(domain, digest, &[], verbose)
}

pub(super) fn display_digest_unique(
    domain: IdDomain,
    digest: &Digest,
    candidates: &[Digest],
    verbose: bool,
) -> String {
    display(
        domain,
        digest.as_str(),
        digest_hex(digest),
        candidates.iter().map(digest_hex),
        verbose,
    )
}

fn parse_plan(reference: &str) -> Result<Selector<PreparedId>> {
    if reference.starts_with("pp-") {
        return Ok(Selector::Exact(PreparedId::new(reference.to_owned())?));
    }
    Ok(Selector::Prefix(parse_typed_prefix(
        reference,
        IdDomain::Plan,
    )?))
}

fn parse_digest(reference: &str, domain: IdDomain) -> Result<Selector<Digest>> {
    if reference.starts_with("sha256-") {
        return Ok(Selector::Exact(Digest::new(reference.to_owned())?));
    }
    Ok(Selector::Prefix(parse_typed_prefix(reference, domain)?))
}

fn parse_typed_prefix(reference: &str, domain: IdDomain) -> Result<String> {
    let (tag, hex) = reference.split_once(':').ok_or_else(|| {
        anyhow::anyhow!(
            "{} reference must be a full canonical ID or {}:<8-64 lowercase hex>",
            domain.tag(),
            domain.tag()
        )
    })?;
    ensure!(
        tag == domain.tag(),
        "{} reference uses the wrong short-ID domain {tag:?}; expected {}:<hex>",
        domain.tag(),
        domain.tag()
    );
    ensure!(
        (MIN_SELECTOR_HEX..=SHA256_HEX).contains(&hex.len()),
        "{} short ID must contain 8-64 lowercase hexadecimal characters",
        domain.tag()
    );
    ensure!(
        hex.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{} short ID must contain only lowercase hexadecimal characters",
        domain.tag()
    );
    Ok(hex.to_owned())
}

fn resolve_unique<T: Clone>(
    domain: IdDomain,
    reference: &str,
    prefix: &str,
    candidates: &[T],
    hex: impl Fn(&T) -> &str,
) -> Result<T> {
    let mut matches = candidates
        .iter()
        .filter(|candidate| hex(candidate).starts_with(prefix));
    let Some(first) = matches.next() else {
        if domain == IdDomain::Plan {
            bail!("no durable plan matches {reference}");
        }
        bail!("no {} matches {reference}", domain.tag());
    };
    if matches.next().is_some() {
        bail!(
            "ambiguous {} short ID {reference}; use a longer {}:<hex> selector",
            domain.tag(),
            domain.tag()
        );
    }
    Ok(first.clone())
}

fn display<'a>(
    domain: IdDomain,
    canonical: &str,
    hex: &str,
    candidates: impl Iterator<Item = &'a str>,
    verbose: bool,
) -> String {
    if verbose {
        return canonical.to_owned();
    }
    let mut length = DEFAULT_DISPLAY_HEX;
    for candidate in candidates {
        if candidate == hex {
            continue;
        }
        let shared = hex
            .bytes()
            .zip(candidate.bytes())
            .take_while(|(left, right)| left == right)
            .count();
        length = length.max(shared.saturating_add(1));
    }
    length = length.min(SHA256_HEX);
    format!("{}:{}", domain.tag(), &hex[..length])
}

fn prepared_hex(plan: &PreparedId) -> &str {
    plan.as_str()
        .strip_prefix("pp-")
        .expect("validated prepared IDs have the canonical prefix")
}

fn digest_hex(digest: &Digest) -> &str {
    digest
        .as_str()
        .strip_prefix("sha256-")
        .expect("validated digests have the canonical prefix")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(hex: char) -> Digest {
        Digest::new(format!("sha256-{}", hex.to_string().repeat(64))).unwrap()
    }

    #[test]
    fn selectors_accept_only_exact_canonical_or_typed_lowercase_prefixes() {
        let candidate = digest('a');
        assert_eq!(
            resolve_digest(
                "gen:aaaaaaaa",
                IdDomain::Generation,
                std::slice::from_ref(&candidate),
            )
            .unwrap(),
            candidate
        );
        assert_eq!(
            resolve_digest(
                &format!("gen:{}", "a".repeat(64)),
                IdDomain::Generation,
                std::slice::from_ref(&candidate)
            )
            .unwrap(),
            candidate
        );
        assert!(resolve_digest("gen:aaaaaaa", IdDomain::Generation, &[]).is_err());
        assert!(resolve_digest("gen:AAAAAAAA", IdDomain::Generation, &[]).is_err());
        assert!(resolve_digest("gen:aaaaaaaa...", IdDomain::Generation, &[]).is_err());
        assert!(resolve_digest("tree:aaaaaaaa", IdDomain::Generation, &[]).is_err());
        assert!(
            resolve_digest(
                &format!("gen:{}", "a".repeat(65)),
                IdDomain::Generation,
                &[]
            )
            .is_err()
        );
        assert_eq!(
            resolve_digest(candidate.as_str(), IdDomain::Generation, &[]).unwrap(),
            candidate
        );

        let plan = PreparedId::new(format!("pp-{}", "b".repeat(64))).unwrap();
        assert_eq!(resolve_plan(plan.as_str(), &[]).unwrap(), plan);
        assert!(resolve_plan("pp-bbbbbbbb", &[]).is_err());
    }

    #[test]
    fn ambiguity_fails_closed_inside_the_selected_domain() {
        let first = PreparedId::new(format!("pp-deadbeef0{}", "0".repeat(55))).unwrap();
        let second = PreparedId::new(format!("pp-deadbeef1{}", "0".repeat(55))).unwrap();
        let error = resolve_plan("plan:deadbeef", &[first, second]).unwrap_err();
        assert!(error.to_string().contains("ambiguous plan short ID"));
    }

    #[test]
    fn human_ids_are_typed_unique_and_never_ellipsized() {
        let first = Digest::new(format!("sha256-{}1{}", "a".repeat(12), "0".repeat(51))).unwrap();
        let second = Digest::new(format!("sha256-{}2{}", "a".repeat(12), "0".repeat(51))).unwrap();
        let rendered = display_digest_unique(
            IdDomain::Generation,
            &first,
            &[first.clone(), second],
            false,
        );
        assert_eq!(rendered, format!("gen:{}1", "a".repeat(12)));
        assert!(!rendered.contains("..."));
        assert_eq!(
            display_digest(IdDomain::Generation, &first, true),
            first.as_str()
        );
    }
}
