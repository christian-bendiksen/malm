//! Interactive confirmation that requires a terminal; scripts must pass `--yes`.
use anyhow::Result;
use std::io::{self, IsTerminal, Write};

pub fn confirm(question: &str) -> Result<bool> {
    if !io::stdin().is_terminal() {
        anyhow::bail!(
            "refusing to prompt for confirmation in a non-interactive session; pass --yes to confirm"
        );
    }
    eprint!("{question} [y/N] ");
    io::stderr().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}
