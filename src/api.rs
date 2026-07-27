//! Process-boundary adapter for the Malm CLI.

use anyhow::Result;

const MAX_ERROR_CHARS: usize = 8_192;

/// Runs one invocation, replaces unsafe control characters, and truncates error
/// text before it crosses the library boundary.
pub fn run_cli() -> Result<i32> {
    crate::cli::dispatch::run().map_err(|error| {
        let rendered = format!("{error:#}");
        let mut bounded = String::with_capacity(rendered.len().min(MAX_ERROR_CHARS));
        for character in rendered.chars().take(MAX_ERROR_CHARS) {
            bounded.push(
                if character.is_control() && character != '\n' && character != '\t' {
                    '?'
                } else {
                    character
                },
            );
        }
        if rendered.chars().count() > MAX_ERROR_CHARS {
            bounded.push_str("... [truncated]");
        }
        anyhow::anyhow!(bounded)
    })
}
