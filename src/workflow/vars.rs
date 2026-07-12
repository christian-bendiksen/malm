//! Prints built-in, global, and per-instance values with their provenance.

use crate::app::context::GlobalCtx;
use crate::config::ProfileSelection;
use crate::lang::diag::Diagnostics;
use crate::lang::typecheck::{TypedProfile, check_profile};
use crate::lang::value::ValueOrigin;
use crate::planning::planner::detect_hostname;
use crate::source::TrustMode;
use crate::workflow::source_resolution::load_resolved_local;
use anyhow::Result;
use owo_colors::OwoColorize;
use std::collections::BTreeMap;

pub fn run(ctx: &GlobalCtx, source: Option<String>) -> Result<()> {
    let mut active_ctx = ctx.clone();
    if let Some(path) = source {
        active_ctx.repo = Some(std::path::PathBuf::from(path));
    }

    let loaded = load_resolved_local(&mut active_ctx)?;
    let cfg = &loaded.config;
    let selection = ProfileSelection::resolve(cfg, active_ctx.profile.as_deref())?;
    let untrusted = matches!(loaded.resolved.trust_mode, TrustMode::Untrusted);

    let mut builtins: BTreeMap<String, String> = BTreeMap::new();
    builtins.insert(
        "malm.target".to_owned(),
        loaded.target_root.display().to_string(),
    );
    if let Some(profile) = selection.selected() {
        builtins.insert("profile.name".to_owned(), profile.to_owned());
    }
    if !untrusted && let Some(hostname) = detect_hostname() {
        builtins.insert("machine.hostname".to_owned(), hostname);
    }

    let globals: BTreeMap<String, (String, String)> = cfg
        .workspace
        .globals
        .values()
        .map(|var| (var.name.clone(), (var.value.display(), var.origin.clone())))
        .collect();

    // Loading already type-checked every profile; resolve again only for display.
    let typed = selection.selected().and_then(|name| {
        let mut diagnostics = Diagnostics::new();
        check_profile(&cfg.workspace, name, &mut diagnostics)
    });

    if active_ctx.json {
        print_json(&selection, &builtins, &globals, typed.as_ref())?;
    } else {
        print_human(cfg, &selection, &builtins, &globals, typed.as_ref());
    }
    Ok(())
}

fn print_human(
    cfg: &crate::config::Config,
    selection: &ProfileSelection,
    builtins: &BTreeMap<String, String>,
    globals: &BTreeMap<String, (String, String)>,
    typed: Option<&TypedProfile>,
) {
    let profile = selection.selected().unwrap_or("none");
    println!(
        "\n  {}  {}",
        "VARS".bold(),
        format!("profile {profile}").dimmed()
    );

    println!("\n  {}", "built-in".bold());
    for (key, value) in builtins {
        println!("     {}  {value}", format!("{key:<24}").cyan());
    }

    println!("\n  {}", "global".bold());
    if globals.is_empty() {
        println!("     {}", "(none)".dimmed());
    }
    for (key, (value, origin)) in globals {
        println!(
            "     {}  {}  {}",
            format!("{key:<24}").cyan(),
            value,
            format!("({origin})").dimmed()
        );
    }

    let Some(typed) = typed else {
        return;
    };
    for instance in &typed.instances {
        let module = cfg.workspace.modules.get(&instance.module);
        let slot = module
            .and_then(|m| m.decl.slot.as_deref())
            .map(|s| format!(" [slot {s}]"))
            .unwrap_or_default();
        let header = if instance.alias == instance.module {
            instance.module.clone()
        } else {
            format!("{} (as {})", instance.module, instance.alias)
        };
        println!("\n  {} {}{}", "module".bold(), header, slot.dimmed());
        if instance.values.is_empty() {
            println!("     {}", "(no inputs)".dimmed());
            continue;
        }
        let mut names: Vec<&String> = instance.values.keys().collect();
        names.sort();
        for name in names {
            let (value, origin) = &instance.values[name];
            let qualified = format!("{}.{name}", instance.alias);
            println!(
                "     {}  {}  {}",
                format!("{qualified:<32}").cyan(),
                value.display(),
                format!("({})", origin.label()).dimmed(),
            );
        }
    }
}

fn print_json(
    selection: &ProfileSelection,
    builtins: &BTreeMap<String, String>,
    globals: &BTreeMap<String, (String, String)>,
    typed: Option<&TypedProfile>,
) -> Result<()> {
    use serde_json::json;
    let instances: Vec<serde_json::Value> = typed
        .map(|typed| {
            typed
                .instances
                .iter()
                .map(|instance| {
                    let mut inputs = serde_json::Map::new();
                    let mut names: Vec<&String> = instance.values.keys().collect();
                    names.sort();
                    for name in names {
                        let (value, origin) = &instance.values[name];
                        inputs.insert(
                            format!("{}.{name}", instance.alias),
                            json!({
                                "value": value.display(),
                                "source": match origin {
                                    ValueOrigin::Default => "default".to_owned(),
                                    ValueOrigin::Profile(p) => format!("profile {p}"),
                                    other => other.label(),
                                },
                            }),
                        );
                    }
                    json!({
                        "instance": instance.alias,
                        "module": instance.module,
                        "inputs": inputs,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let global_obj: serde_json::Map<String, serde_json::Value> = globals
        .iter()
        .map(|(key, (value, src))| (key.clone(), json!({ "value": value, "source": src })))
        .collect();
    let builtins_obj: serde_json::Map<String, serde_json::Value> = builtins
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    let payload = json!({
        "profile": selection.selected(),
        "active_profiles": selection.active_names(),
        "builtins": builtins_obj,
        "global": global_obj,
        "instances": instances,
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}
