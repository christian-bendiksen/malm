//! Library entry point for running the CLI.
use crate::cli::dispatch;
use anyhow::Result;

pub fn run_cli() -> Result<i32> {
    // Sanitize the full error chain before attacker-controlled paths reach the terminal.
    dispatch::run()
        .map_err(|error| anyhow::anyhow!("{}", crate::sanitize::terminal(&format!("{error:#}"))))
}
