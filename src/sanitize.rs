//! Terminal output sanitization: strips control characters and Unicode
//! bidi overrides (Trojan-Source) from attacker-influenceable strings.

use std::borrow::Cow;

pub fn terminal(s: &str) -> Cow<'_, str> {
    if s.chars().any(is_unsafe) {
        Cow::Owned(s.chars().filter(|c| !is_unsafe(*c)).collect())
    } else {
        Cow::Borrowed(s)
    }
}

fn is_unsafe(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t') || is_bidi_override(c)
}

// The bidi override/isolate set used in Trojan-Source attacks
// (CVE-2021-42574).
fn is_bidi_override(c: char) -> bool {
    matches!(c,
        '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
        | '\u{200E}'
        | '\u{200F}'
    )
}

/// Print a sanitized warning to stderr.
///
/// Use this for warnings containing remote-config or filesystem data. Top-level
/// errors are already sanitized by `api::run_cli`.
#[macro_export]
macro_rules! warn_term {
    ($($arg:tt)*) => {{
        eprintln!("{}", $crate::sanitize::terminal(&format!($($arg)*)));
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_string_passes_through_unchanged() {
        let s = "deployed ~/.bashrc -> ~/.config/foo";
        match terminal(s) {
            Cow::Borrowed(out) => assert_eq!(out, s),
            Cow::Owned(_) => panic!("clean string should be borrowed as-is"),
        }
    }

    #[test]
    fn control_chars_are_stripped_but_newline_and_tab_survive() {
        let s = "a\x07bell\x00null\x08back\nwith\ttab";
        let cleaned = terminal(s);
        assert_eq!(&*cleaned, "abellnullback\nwith\ttab");
    }

    #[test]
    fn terminal_is_idempotent() {
        // Sanitizing an already-cleaned value must not change it again.
        for s in [
            "clean",
            "a\x01b\x07c",
            "trojan\u{202E}source",
            "mix\x00\u{2066}\u{202B}end",
        ] {
            let once = terminal(s).into_owned();
            let twice = terminal(&once).into_owned();
            assert_eq!(once, twice, "idempotence failed for {s:?}");
        }
    }

    #[test]
    fn trojan_source_bidi_overrides_are_stripped() {
        // CVE-2021-42574: LRE/RLE/PDF/LRO/RLO and the isolate sequences.
        let attacks = [
            '\u{202A}', // LRE
            '\u{202B}', // RLE
            '\u{202C}', // PDF
            '\u{202D}', // LRO
            '\u{202E}', // RLO  (the classic spoofing override)
            '\u{2066}', // LRI
            '\u{2067}', // RLI
            '\u{2068}', // FSI
            '\u{2069}', // PDI
            '\u{200E}', // LRM
            '\u{200F}', // RLM
        ];
        for c in attacks {
            assert!(
                is_bidi_override(c),
                "{c:?} should be flagged as bidi override"
            );
            let s = format!("path{c}");
            let cleaned = terminal(&s);
            assert!(!cleaned.contains(c), "{c:?} survived sanitization");
        }
    }

    #[test]
    fn ansi_escape_and_csi_sequences_are_removed() {
        // Attacker-influenced filenames/errors must not be able to move the
        // cursor, clear the screen, or rewrite the terminal title.
        let s = "\x1b[2J\x1b[0;31mred\x1b[0m\x1b]0;title\x07";
        let cleaned = terminal(s);
        assert!(!cleaned.contains('\x1b'), "ESC survived");
        assert!(!cleaned.contains('\x07'), "BEL survived");
        assert!(cleaned.contains("red"), "visible text dropped");
    }

    #[test]
    fn empty_and_clean_edge_cases() {
        assert_eq!(&*terminal(""), "");
        assert_eq!(&*terminal("plain ascii 123"), "plain ascii 123");
    }
}
