//! Validation for state names, transaction IDs, and Git commit SHAs.
use anyhow::Result;

pub fn validate_name(s: &str, label: &str) -> Result<()> {
    if s.is_empty()
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!("{label} must contain only [A-Za-z0-9_-], got: {s:?}");
    }
    Ok(())
}

// User input may use an abbreviated SHA; persisted resolved SHAs must be full length.
pub fn validate_commit_sha(s: &str) -> Result<()> {
    if s.len() < 7 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("commit SHA must be at least 7 hex digits (got: {s:?})");
    }
    Ok(())
}

pub fn validate_resolved_commit_sha(s: &str) -> Result<()> {
    if s.len() != 40 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("resolved commit SHA must be exactly 40 hex digits (got: {s:?})");
    }
    Ok(())
}

/// Abbreviate a commit SHA without slicing through a UTF-8 character.
///
/// Valid SHAs are ASCII, but a corrupted or tampered manifest may contain
/// arbitrary UTF-8. Iterating characters keeps display code from panicking.
pub fn short_commit(commit: &str, len: usize) -> String {
    commit.chars().take(len).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_commit_truncates_ascii_sha() {
        assert_eq!(short_commit("0123456789abcdef", 7), "0123456");
        assert_eq!(short_commit("0123456789abcdef", 8), "01234567");
        assert_eq!(short_commit("short", 12), "short");
    }

    #[test]
    fn short_commit_never_panics_on_non_char_boundary() {
        // A byte slice at index 8 would split a codepoint and panic.
        let corrupted = "❊❊❊❊❊❊❊❊❊❊0123456789abcdef";
        let got = short_commit(corrupted, 8);
        assert_eq!(got, "❊❊❊❊❊❊❊❊");
    }

    #[test]
    fn validate_resolved_commit_sha_rejects_non_hex() {
        assert!(validate_resolved_commit_sha("❊".repeat(40).as_str()).is_err());
        assert!(validate_resolved_commit_sha("g".repeat(40).as_str()).is_err());
        assert!(validate_resolved_commit_sha("abc").is_err());
        assert!(validate_resolved_commit_sha(&"a".repeat(40)).is_ok());
    }
}
