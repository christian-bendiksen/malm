//! Profile discovery, including filtering out inheritance-only profiles.

use crate::app::context::GlobalCtx;
use crate::workflow::source_resolution::load_resolved_local;
use anyhow::Result;
use owo_colors::OwoColorize;

pub fn run(ctx: &GlobalCtx, selectable_only: bool) -> Result<()> {
    let mut active_ctx = ctx.clone();
    let loaded = load_resolved_local(&mut active_ctx)?;
    let mut profiles: Vec<_> = loaded
        .config
        .workspace
        .profiles
        .iter()
        .filter(|profile| !selectable_only || !profile.abstract_)
        .collect();
    profiles.sort_by(|left, right| left.name.cmp(&right.name));

    if ctx.json {
        let rows: Vec<_> = profiles
            .iter()
            .map(|profile| {
                serde_json::json!({
                    "name": &profile.name,
                    "abstract": profile.abstract_,
                    "selectable": !profile.abstract_,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    println!("\n  {}", "PROFILES".bold());
    if profiles.is_empty() {
        println!("     {}", "(none)".dimmed());
    }
    for profile in profiles {
        if profile.abstract_ {
            println!("     {}  {}", profile.name, "abstract".dimmed());
        } else {
            println!("     {}", profile.name);
        }
    }
    Ok(())
}
