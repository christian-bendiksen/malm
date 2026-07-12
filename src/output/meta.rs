//! Prints the loaded-source banner (config meta + redacted source label).

use crate::app::validation::short_commit;
use crate::config::LoadedConfigSource;
use crate::output::display::format_short_path;
use crate::sanitize::terminal;
use crate::source::git::redact_url;
use crate::source::{SourceIdentity, SourceKind};
use owo_colors::OwoColorize;

pub fn print_loaded_source(loaded: &LoadedConfigSource) {
    let Some(meta) = &loaded.config.meta else {
        return;
    };

    let source = source_label(&loaded.resolved.identity);
    match &meta.name {
        Some(name) => println!(
            "\n  {}  {}",
            terminal(name).bold(),
            format!("· {source}").dimmed()
        ),
        None => println!("\n  {}", source.bold()),
    }

    let mut detail = Vec::new();
    if let Some(author) = &meta.author {
        detail.push(terminal(author).into_owned());
    }
    if let Some(homepage) = &meta.homepage {
        detail.push(terminal(homepage).into_owned());
    }
    if !detail.is_empty() {
        println!("  {}", detail.join("  ·  ").dimmed());
    }
}

fn source_label(identity: &SourceIdentity) -> String {
    match &identity.kind {
        SourceKind::Local { path } => format_short_path(path),
        SourceKind::Git { url, commit } => {
            let short = short_commit(commit, 8);
            format!("{} @ {}", terminal(&redact_url(url)), short)
        }
    }
}
